import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("LITELLM_URL", "http://litellm:4000")
os.environ.setdefault("MASTER_KEY", "sk-master-secret-key-12345")
os.environ.setdefault("PLUGIN_KEYS", "plugin_opencode_costs")
os.environ.setdefault("LOG_LEVEL", "minimal")
