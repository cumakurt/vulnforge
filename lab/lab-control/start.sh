#!/bin/sh
# Start uvicorn on port 9100 (lab control API)
# AND on port 80 (IMDSv1 metadata simulator accessible at 169.254.169.100)
uvicorn main:app --host 0.0.0.0 --port 9100 --log-level info &
uvicorn main:app --host 0.0.0.0 --port 80   --log-level warning &
wait
