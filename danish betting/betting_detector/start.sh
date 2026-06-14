#!/bin/zsh
# ─────────────────────────────────────────────────────────────────────────────
# start.sh — Start the Betting Detector API + Dashboard
#
# Usage (from anywhere):
#   bash /Users/mehtabsinghahluwalia/danish\ betting/betting_detector/start.sh
#
# Or make executable and run:
#   chmod +x start.sh && ./start.sh
# ─────────────────────────────────────────────────────────────────────────────

PROJECT_DIR="/Users/mehtabsinghahluwalia/danish betting/betting_detector"
PYTHON="$PROJECT_DIR/.venv311/bin/python"
STREAMLIT="$PROJECT_DIR/.venv311/bin/streamlit"

export PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK=True
export USE_BERT=true
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1
export NUMEXPR_NUM_THREADS=1

echo "🎰 Betting Detector — Starting services..."
echo ""

# Kill anything already on ports 8000 / 8501
lsof -ti:8000 | xargs kill -9 2>/dev/null
lsof -ti:8501 | xargs kill -9 2>/dev/null
sleep 1

# Start FastAPI in the background
echo "🚀 Starting API on http://localhost:8000 ..."
cd "$PROJECT_DIR"
"$PYTHON" app.py &
API_PID=$!

# Give it 3 seconds to start
sleep 3

# Start Streamlit in the background
echo "📊 Starting Dashboard on http://localhost:8501 ..."
"$STREAMLIT" run "$PROJECT_DIR/dashboard/app.py" \
    --server.port 8501 \
    --server.headless true \
    --browser.gatherUsageStats false &
DASH_PID=$!

echo ""
echo "✅ Both services started!"
echo "   API:       http://localhost:8000"
echo "   API Docs:  http://localhost:8000/docs"
echo "   Dashboard: http://localhost:8501"
echo ""
echo "Press Ctrl+C to stop both services."
echo ""

# Wait and forward signals to both processes
trap "kill $API_PID $DASH_PID 2>/dev/null; echo 'Stopped.'" SIGINT SIGTERM
wait $API_PID $DASH_PID
