# =============================================================================
# SECRETS SETUP GUIDE
# =============================================================================
# DO NOT commit actual keys to this file!
# This is a reference for setting up GitHub organization secrets.
# =============================================================================

# Step 1: Go to https://github.com/IronCityIT → Settings → Secrets → Actions
# Step 2: Click "New organization secret" for each of these:

# -----------------------------------------------------------------------------
# GROQ_API_KEY
# -----------------------------------------------------------------------------
# Get from: https://console.groq.com/keys
# Free tier: Yes (generous limits)
# Used for: Llama 3.3 70B, Llama 3.1 8B
#
# Example format: gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# -----------------------------------------------------------------------------
# OPENROUTER_API_KEY  
# -----------------------------------------------------------------------------
# Get from: https://openrouter.ai/keys
# Free tier: $5 credit on signup
# Used for: Claude 3 Haiku, GPT-4o-mini, Mistral Large, Gemma 2, Qwen, DeepSeek
#
# Example format: sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# -----------------------------------------------------------------------------
# GEMINI_API_KEY
# -----------------------------------------------------------------------------
# Get from: https://aistudio.google.com/app/apikey
# Free tier: Yes (generous limits)
# Used for: Gemini 2.5 Flash
#
# Example format: AIzaXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxX

# =============================================================================
# TESTING LOCALLY
# =============================================================================
# Create a .env.local file (gitignored) with:
#
# export GROQ_API_KEY="your_key_here"
# export OPENROUTER_API_KEY="your_key_here"
# export GEMINI_API_KEY="your_key_here"
#
# Then: source .env.local && python src/consensus_engine.py tests/sample_findings.json --pretty
