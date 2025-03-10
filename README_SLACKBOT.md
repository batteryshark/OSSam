# OSSam Slack Bot

A Slack bot integration for OSSam (Open Source Software Assessment and Management Tool) that allows users to analyze open-source packages directly from Slack.

## Features

- Direct message the bot with a package name to analyze it
- Bot reacts with 👀 while processing
- Results are posted in a thread
- Success is indicated with a ✅ reaction
- Failure is indicated with a ❌ reaction

## Setup

1. Create a Slack app in your workspace:
   - Go to [api.slack.com/apps](https://api.slack.com/apps)
   - Click "Create New App" → "From scratch"
   - Name it "OSSam" and select your workspace

2. Configure Socket Mode:
   - Navigate to "Socket Mode" in the sidebar and enable it
   - Generate an app-level token with the `connections:write` scope
   - Save this token (it starts with `xapp-`)

3. Set up Bot Token Scopes:
   - Navigate to "OAuth & Permissions" in the sidebar
   - Add the following scopes:
     - `app_mentions:read`
     - `chat:write`
     - `im:history`
     - `im:read`
     - `reactions:read`
     - `reactions:write`
     - `canvases:write` (for Canvas creation)
     - `files:read`
     - `files:write` (for fallback file upload)
     - `team:read` (to construct Canvas URLs)

4. Enable Event Subscriptions:
   - Navigate to "Event Subscriptions" and turn it on
   - Subscribe to these bot events:
     - `message.im`
     - `app_mention`

5. Install the app to your workspace:
   - Navigate to "Install App" in the sidebar
   - Click "Install to Workspace"
   - Authorize the requested permissions
   - Save the Bot User OAuth Token (it starts with `xoxb-`)

6. Add environment variables to your `.env` file:
   ```
   SLACK_APP_TOKEN=xapp-...
   SLACK_BOT_TOKEN=xoxb-...
   ```

## Running the Bot

Run the bot with the following command:
```bash
python ossam_slack_bot.py
```

The bot will connect to Slack via Socket Mode and begin listening for direct messages.

## Usage

1. Invite the OSSam bot to a channel or start a DM
2. Send a package name, e.g., `express 4.17.1`, `axios`
3. Wait for the analysis to complete
4. View the results in the thread

### Canvas Reports

You can also request a Canvas report for richer formatting and persistence:

1. Include `create_a_canvas` anywhere in your message, e.g., `create_a_canvas axios` or `axios create_a_canvas`
2. The bot will create a Canvas with the analysis results and share the link in the thread
3. Canvas titles follow the format: `OSSam Analysis: {package_name} {package_version}`

Canvas reports are perfect for sharing with your team, as they:
- Persist in your workspace's knowledge base
- Support collaboration with comments and reactions
- Provide better formatting than message threads
- Can be shared with anyone in your workspace

If Canvas creation fails for any reason (including free workspace limitations), the bot will automatically fall back to posting the markdown-formatted message in the thread.