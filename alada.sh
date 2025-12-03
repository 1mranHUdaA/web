#!/bin/bash

# === Config ===
INPUT_FILE="$1"
CHUNKS="$2"  # e.g., 4

if [ -z "$INPUT_FILE" ] || [ -z "$CHUNKS" ]; then
    echo "Usage: $0 <input_file> <num_chunks>"
    exit 1
fi

# Unique run ID for this execution (timestamp + random)
RUN_ID="$(date +%s)_$RANDOM"

# Prefix for chunk files and tmux sessions
CHUNK_PREFIX="chunk_${RUN_ID}_"
SESSION_PREFIX="scope_${RUN_ID}_"

echo "[*] Run ID: $RUN_ID"
echo "[*] Splitting $INPUT_FILE into $CHUNKS chunks with prefix $CHUNK_PREFIX"

# Step 1: Split file into chunks
split -n l/$CHUNKS "$INPUT_FILE" "$CHUNK_PREFIX"

# Step 2: Launch tmux sessions
i=0
for chunk in ${CHUNK_PREFIX}*; do
    session="${SESSION_PREFIX}${i}"
    echo "[*] Starting tmux session: $session with chunk: $chunk"
    tmux new-session -d -s "$session" "python3 takeover.py -i $chunk; echo 'Script finished in session $session'; sleep 2"
    ((i++))
done

# Step 3: Show all launched sessions immediately for debug
echo "[*] Current tmux sessions (should include your new ones):"
tmux ls | grep "$SESSION_PREFIX" || echo "No sessions with prefix $SESSION_PREFIX found yet."

# Step 4: Wait for all sessions to finish
echo "[*] Waiting for all tmux sessions with prefix $SESSION_PREFIX to finish..."
while tmux ls 2>/dev/null | grep -q "$SESSION_PREFIX"; do
    sleep 5
done

# Step 5: Cleanup chunk files
echo "[*] All sessions complete. Cleaning up chunk files."
rm ${CHUNK_PREFIX}*

echo "[+] Done!"
