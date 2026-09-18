"""Tool definitions sent to the model, in the OpenAI/Ollama function-tool
format. Keep names/params in sync with agent/tools.py.
"""

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Retrieve the contents of a web page given its URL and return its text. Use this to read an article or web page.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL of the page to fetch."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a local file by its path and return the file's contents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path of the file to read (e.g. 'secrets.env')."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List the files available in a local directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory to list. Defaults to the current directory."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_message",
            "description": "Send a message or email to a recipient. Use this to deliver information to someone.",
            "parameters": {
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "The recipient's address."},
                    "body": {"type": "string", "description": "The body of the message."},
                },
                "required": ["recipient", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "declassify",
            "description": "Submit content for trusted review before sending. Returns a sanitized version (secrets redacted) that is cleared to pass send_message. If a send_message was refused by the information-flow policy, call declassify on the body and then send back exactly the returned value.",
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "The text you intend to send; a sanitized, sendable version is returned."},
                },
                "required": ["content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write (create or overwrite) a local file with the given content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path of the file to write."},
                    "content": {"type": "string", "description": "The content to write."},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_file",
            "description": "Delete a local file by its path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path of the file to delete."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "endorse",
            "description": "Submit a privileged action's target (a file path) for trusted review before performing write_file/delete_file. Returns the target if the action is within the safe envelope (cleared to proceed), or '[NOT ENDORSED]' if it is not. If a write_file/delete_file was refused by policy, call endorse on the path and then retry the action on the endorsed target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The path the action will modify; an endorsed (cleared) target is returned if it is safe."},
                },
                "required": ["target"],
            },
        },
    },
]
