#!/usr/bin/env python3
"""
OSSam Slack Bot

A Slack integration for the Open Source Software Assessment and Management Tool.
This bot allows users to analyze open-source packages directly from Slack by
sending a direct message with the package name.
"""

import os
import sys
import logging
import time
import traceback
from pathlib import Path
from threading import Thread
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# Set up logging - only show warnings and errors in console, but log everything to file
# Create file handler that logs everything
file_handler = logging.FileHandler("ossam_bot.log")
file_handler.setLevel(logging.DEBUG)

# Create console handler with a higher log level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)  # Only show warnings and errors in console

# Create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Get the logger and set its level
logger = logging.getLogger("OSSam-Bot")
logger.setLevel(logging.DEBUG)  # Log everything to the file

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Prevent double logging by not propagating to root logger
logger.propagate = False

# Also silence noisy loggers from dependencies
for noisy_logger in ['slack_bolt', 'slack_sdk', 'urllib3', 'asyncio']:
    logging.getLogger(noisy_logger).setLevel(logging.WARNING)

# Load environment variables from .env file
load_dotenv()

# Check if tokens are available
app_token = os.environ.get("SLACK_APP_TOKEN")
bot_token = os.environ.get("SLACK_BOT_TOKEN")

if not app_token or not bot_token:
    logger.error("Missing Slack tokens. Make sure SLACK_APP_TOKEN and SLACK_BOT_TOKEN are set in .env")
    print("Missing Slack tokens. Make sure SLACK_APP_TOKEN and SLACK_BOT_TOKEN are set in .env")
    sys.exit(1)

# Initialize the Slack app with the bot token
app = App(token=bot_token)

# Handler for direct messages
@app.event("message")
def handle_message_events(body):
    event = body.get("event", {})
    
    # Check if this is a direct message
    if event.get("channel_type") != "im":
        return
    
    # If it's a bot message, ignore it
    if event.get("bot_id"):
        return
    
    # Extract message details
    message_text = event.get("text", "").strip()
    channel_id = event.get("channel")
    message_ts = event.get("ts")
    user_id = event.get("user")
    
    if not message_text:        
        return
    
    logger.info(f"Processing DM from {user_id}: '{message_text}'")
    
    # Process the message in a separate thread to avoid timeouts
    thread = Thread(target=process_package_request, 
                   args=(message_text, channel_id, message_ts))
    thread.start()

def create_canvas(client, channel_id, package_name, package_version, markdown_content):
    """
    Create a Canvas in Slack with the package analysis results
    
    Uses the canvases_create method to create a new canvas document with markdown content
    """
    import time
    import json
    from urllib.parse import quote
    
    # Generate a unique title for the canvas
    timestamp = int(time.time())
    canvas_title = f"OSSam Analysis: {package_name} {package_version}"
    
    logger.info(f"Creating canvas with title: {canvas_title}")
    
    try:
        # Create a new canvas with markdown content
        # The document_content field expects a JSON object with markdown content
        document_content = {
            "type": "markdown",
            "markdown": markdown_content
        }
        
        # Make the API call to create a canvas
        canvas_response = client.api_call(
            "canvases.create", 
            json={
                "title": canvas_title,
                "document_content": document_content
            }
        )
        
        if not canvas_response.get("ok", False):
            logger.error(f"Failed to create canvas: {canvas_response.get('error')}")
            return False, f"Failed to create canvas: {canvas_response.get('error')}"
        
        # Extract the canvas ID and team ID from the response
        canvas_id = canvas_response.get("canvas", {}).get("id")
        team_id = canvas_response.get("canvas", {}).get("team_id")
        
        if not canvas_id or not team_id:
            logger.error("Canvas created but no canvas ID or team ID returned")
            return False, "Canvas created but could not retrieve canvas details"
        
        # Construct the canvas URL - format is: https://{workspace-url}.slack.com/docs/{team_id}/{canvas_id}
        # We need to get the workspace URL from an API call
        team_info = client.team_info()
        workspace_domain = team_info.get("team", {}).get("domain", "slack")
        
        canvas_url = f"https://{workspace_domain}.slack.com/docs/{team_id}/{canvas_id}"
        logger.info(f"Canvas URL: {canvas_url}")
        
        # Share the canvas in the channel
        share_message = (
            f"I've created a Canvas with the package analysis for *{package_name} {package_version}*.\n\n"
            f"View it here: {canvas_url}"
        )
        
        client.chat_postMessage(
            channel=channel_id,
            text=share_message
        )
        
        return True, canvas_url
        
    except Exception as e:
        logger.error(f"Error creating canvas: {e}")
        import traceback
        traceback.print_exc()
        
        # Return a message about the canvas failure
        # For free teams or when canvas creation fails for other reasons
        if "not_allowed_token_type" in str(e) or "access_denied" in str(e):
            message = (
                "ℹ️ Canvas creation is not available on your Slack workspace plan. "
                "I'll provide the report directly in the thread instead."
            )
        else:
            message = (
                f"❗ Canvas creation failed: {str(e)}\n"
                "I'll provide the report directly in the thread instead."
            )
        
        # Simply return false - we'll fall back to the standard message response
        return False, message

def process_package_request(message_text, channel_id, message_ts):
    """Process a package analysis request in a separate thread"""
    client = app.client
    
    # Check if the user wants to create a canvas
    create_canvas_report = False
    if "create_a_canvas" in message_text:
        create_canvas_report = True
        message_text = message_text.replace("create_a_canvas", "").strip()
        logger.debug(f"Canvas report requested, cleaned message: '{message_text}'")
    
    # Add eyes reaction to show we're processing
    try:
        client.reactions_add(
            channel=channel_id,
            name="eyes",
            timestamp=message_ts
        )
        logger.debug("Added 'eyes' reaction")
    except Exception as e:
        logger.error(f"Error adding reaction: {e}")
    
    # Process the package analysis in a try-except block
    try:
        # Import here to avoid circular imports
        from package_evaluator import package_evaluator, generate_markdown_report
        
        # Print minimal user-facing message for long-running operation
        package_name = message_text.split()[0] if message_text else "package"
        print(f"📊 Analyzing {package_name}... (this may take a minute)")
        logger.debug(f"Starting analysis for package: {message_text}")
        
        # Call the package evaluator with the message text
        evaluation_results = package_evaluator(message_text)
        logger.debug("Analysis complete, generating report")
        
        # Get package info for canvas title
        package_info = evaluation_results.get("PackageInfo", {})
        package_name = package_info.get("Name", message_text.split()[0])
        package_version = package_info.get("Requested Package Version", 
                                          package_info.get("Latest Package Version", "latest"))
        
        # Generate the markdown report
        markdown_report = generate_markdown_report(
            package_info=package_info,
            license_info=evaluation_results.get("LicenseInfo", {}),
            security_info=evaluation_results.get("SecurityInfo", {}),
            verdict={
                "Verdict": evaluation_results.get("Verdict", "Unknown"), 
                "Explanation": evaluation_results.get("Explanation", "")
            }
        )
        
        # Check if the report contains an error message
        if "An error occurred while evaluating the package" in markdown_report:
            logger.warning("Error detected in the generated report")
            
            # Extract error details if possible
            error_details = "No specific error details available."
            try:
                # Try to find text after the error message
                error_text = markdown_report.split("An error occurred while evaluating the package")[1]
                if error_text and len(error_text) > 5:  # Make sure we have some content
                    error_details = error_text.strip()
            except:
                pass
            
            # Post error message in thread
            client.chat_postMessage(
                channel=channel_id,
                thread_ts=message_ts,
                text=f"❌ Analysis failed: An error occurred while evaluating package '{message_text}'.\n\n{error_details}"
            )
            
            # Update reactions - remove eyes and add x
            client.reactions_remove(
                channel=channel_id,
                name="eyes",
                timestamp=message_ts
            )
            
            client.reactions_add(
                channel=channel_id,
                name="x",
                timestamp=message_ts
            )
        else:
            logger.debug("Analysis successful")
            
            # Create a Canvas if requested
            canvas_url = None
            if create_canvas_report:
                logger.debug("Creating Canvas for report")
                success, result = create_canvas(
                    client, 
                    channel_id, 
                    package_name, 
                    package_version, 
                    markdown_report
                )
                
                if success:
                    canvas_url = result
                    logger.debug(f"Canvas created successfully: {canvas_url}")
                    print(f"✅ Canvas created for {package_name}")
                else:
                    logger.warning(f"Canvas creation failed or unavailable: {result}")
                    # If we got a message back, post it to explain the fallback
                    if isinstance(result, str) and len(result) > 5:
                        client.chat_postMessage(
                            channel=channel_id,
                            thread_ts=message_ts,
                            text=result
                        )
            
            # Post the report in a thread
            report_text = markdown_report
            if canvas_url:
                # Add a link to the Canvas at the top of the report
                report_prefix = f"📝 *Report also available as a Canvas*: {canvas_url}\n\n"
                report_text = report_prefix + markdown_report
            
            # Post the report in a thread
            client.chat_postMessage(
                channel=channel_id,
                thread_ts=message_ts,
                text=report_text
            )
            
            # Update reactions - remove eyes and add check mark
            client.reactions_remove(
                channel=channel_id,
                name="eyes",
                timestamp=message_ts
            )
            
            client.reactions_add(
                channel=channel_id,
                name="white_check_mark", 
                timestamp=message_ts
            )
        
        logger.debug("Successfully processed package request")
        print(f"✅ Analysis completed for {package_name}")
        
    except Exception as e:
        traceback.print_exc()
        logger.error(f"Error processing package analysis: {e}")
        print(f"❌ Error analyzing package: {str(e)}")
        
        # Post error message in thread
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text=f"❌ Sorry, I encountered an error analyzing this package: ```{str(e)}```"
        )
        
        # Update reactions - remove eyes and add x
        client.reactions_remove(
            channel=channel_id,
            name="eyes",
            timestamp=message_ts
        )
        
        client.reactions_add(
            channel=channel_id,
            name="x",
            timestamp=message_ts
        )

# Listen to app_mention events for debugging
@app.event("app_mention")
def handle_app_mentions(body, say):
    logger.info(f"Got app mention: {body}")
    say("I'm OSSam! Send me a package name in a direct message to analyze it.")

# Debug listener to see all events
@app.event("*")
def debug_all_events(body):
    event_type = body.get("event", {}).get("type")
    logger.debug(f"Received event type: {event_type}")

def start_bot():
    """Start the OSSam Slack bot"""
    logger.debug("Starting OSSam Slack bot...")
    
    # Print startup message
    print("""
    ==================================
         OSSam Slack Bot
    ==================================
    
    Starting up...
    """)
    
    # Start the app using Socket Mode with the callback
    handler = SocketModeHandler(app, app_token)
    
    try:
        handler.start()
    except Exception as e:
        traceback.print_exc()
        logger.error(f"Error starting Socket Mode: {e}")
        print(f"\n❌ Error connecting to Slack: {e}\n"
              f"Make sure your tokens are correct and Socket Mode is enabled for your app.")

if __name__ == "__main__":
    start_bot()