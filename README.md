# Unifon Queue Management Sample

Python CLI for managing queues on the Unifon switchboard platform. It demonstrates token caching with the client credentials grant and covers listing queues, inspecting members, and toggling readiness. 

Note: This sample was written by OpenAI/Codex using gpt-5.1-codex-max, and is only provided as an example and not for production use.

## Prerequisites
- Python 3.8+
- `requests` library (`pip install requests`)

## Configuration
- Default API host: `https://bnapi.test.unifonip.no`
- Supply credentials via flags or environment variables:
  - Flags: `--client-id`, `--client-secret`, `--grant-type` (defaults to `client_credentials`), `--host`
  - Environment: `UNIFON_CLIENT_ID`, `UNIFON_CLIENT_SECRET`, `UNIFON_GRANT_TYPE`, `UNIFON_HOST`
- Tokens are cached in `token.json` in the working directory. The script reuses the token until close to expiry.

## Installation
```bash
pip install requests
```

## Usage
Run the script from the repo root:
```bash
python queue_manager.py <command> [options]
```

### List queues
```bash
python queue_manager.py list-queues
```

### List members of a queue
```bash
python queue_manager.py list-members --queue-id 12345
```

### Set readiness for an agent in one queue
```bash
python queue_manager.py set-ready --agent AGENT_ID --queue-id 12345 --ready true
```
Use `--ready false` to set not ready.

### Set readiness for an agent across all queues
Looks up every queue where the agent appears and updates readiness for each.
```bash
python queue_manager.py set-ready-all --agent AGENT_ID --ready true
```

## Notes
- Responses and errors are printed to stdout/stderr for clarity.
- The sample uses the queue summary endpoint to discover queues and members, then calls the readiness endpoint for updates.

## Examples 

```
# python3 queue_manager.py list-queues
# python3 queue_manager.py list-members --queue-id 16 
# python3 queue_manager.py set-ready --agent +4712345678 --queue-id 16 --ready true
# python3 queue_manager.py set-ready --agent +4712345678 --queue-id 16 --ready false
# python3 queue_manager.py set-ready-all --agent +4712345678 --ready true
# python3 queue_manager.py set-ready-all --agent +4712345678 --ready false

```
