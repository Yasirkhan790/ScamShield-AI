import sys
import os

# Insert repository root to sys.path so 'backend.*' imports resolve cleanly during pytest execution
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
