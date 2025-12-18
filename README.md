---

### 🔧 About `.gitignore` vs `requirements.txt`
- **`.gitignore`**: Prevents bulky folders like `.venv/` or caches from being pushed. It doesn’t affect your ability to know dependencies.  
- **`requirements.txt`**: Should list packages your code imports. Even if `.venv` is ignored, you can still generate it by running:
  ```bash
  pip freeze > requirements.txt
