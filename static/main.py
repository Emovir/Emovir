# This file is deprecated. All functionality has been moved to app.py
from app import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)