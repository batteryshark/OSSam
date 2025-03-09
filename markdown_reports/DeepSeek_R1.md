# OSS Assessment Report: DeepSeek-R1 Latest

*Generated on: 2025-03-08 17:57:07*


## 📦 Package Information

- **Name:** DeepSeek-R1
- **Requested Version:** Latest
- **Latest Version:** Latest
- **Primary Language:** N/A
- **Description:** DeepSeek-R1 is a first-generation reasoning model trained using large-scale reinforcement learning (RL) to solve complex reasoning tasks across domains such as math, code, and language. The model leverages RL to develop reasoning capabilities, which are further enhanced through supervised fine-tuning (SFT).
- **Repository:** [https://huggingface.co/deepseek-ai/DeepSeek-R1](https://huggingface.co/deepseek-ai/DeepSeek-R1)
- **Maintained By:** deepseek-ai

## 🗒️ Package Evaluation

- **Advisory:** ❌ Do not Use
- **Explanation:** DeepSeek-R1 exhibits several critical security vulnerabilities, including susceptibility to jailbreak attacks, prompt injection, and the generation of harmful content. Additionally, data privacy concerns related to data transmission to China and potential vulnerabilities in the DeepSeek AI app elevate the risk. The combination of these factors warrants a High-risk rating. License (MIT License) is permitted for use.

## 📜 License Evaluation

- **License:** MIT License
- **Status:** ✅ Allowed
- **Notes:** The MIT License is permissive and business-friendly. It allows for commercial use, modification, distribution, and private use, with minimal restrictions. (Normalized from 'MIT License' to 'MIT')

## 🔒 Security Evaluation

- **Security Risk:** ❌ High
- **Risk Assessment:** DeepSeek-R1 exhibits several critical security vulnerabilities, including susceptibility to jailbreak attacks, prompt injection, and the generation of harmful content. Additionally, data privacy concerns related to data transmission to China and potential vulnerabilities in the DeepSeek AI app elevate the risk. The combination of these factors warrants a High-risk rating.

### Other Security Concerns:

- Jailbreak vulnerabilities (Evil Jailbreak, Crescendo, Deceptive Delight, Bad Likert Judge).
- Prompt injection vulnerabilities.
- Insecure code generation.
- Harmful content generation.
- Data transmission to China.
- Weak encryption and SQL injection flaws in DeepSeek AI app (potential).
- Publicly accessible DeepSeek database with chat history and sensitive information.

### Repository Health:

- Uncertainty about the repository's age (reports conflicting information, including a future date).
- Relatively small number of contributors (5).
- Vulnerability to jailbreak and prompt injection attacks.
- Potential for generating insecure code.
- Potential for generating harmful and biased content.
- Data privacy concerns related to data transmission to China.
- Weak encryption and SQL injection flaws in the DeepSeek AI app (potential).

## 📚 References

1. https://huggingface.co/deepseek-ai/DeepSeek-R1
2. https://build.nvidia.com/deepseek-ai/deepseek-r1/modelcard
3. https://github.com/deepseek-ai/DeepSeek-R1/blob/main/LICENSE
4. Search results from analyze_repository_health tool
5. Search results from search_vulnerabilities tool