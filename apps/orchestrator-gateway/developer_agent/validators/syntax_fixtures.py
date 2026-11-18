"""HCL syntax fixtures for the generated syntax-code table (lane 8B §4.2, Step 1 RT F4).

The repair-acceptance rule treats a file whose syntax diagnostic disappeared as "visibility improved": semantic
errors that the syntax error used to hide may appear there and are accepted. Which TF.* codes are syntax codes is
not typed by hand: tests/test_step1_s1b_loop.py runs each fixture through a real engine (when one is available) and
compares the codes it reports with syntax_codes.json, which is generated data (one column per engine version).
"""

SYNTAX_FIXTURES = {
    "stray_bracket": 'output "x" {\n  value = [1, 2]]\n}\n',
    "missing_newline": 'resource "google_pubsub_topic" "t" {\n  name = "t" labels = {}\n}\n',
    "unclosed_block": 'resource "google_pubsub_topic" "t" {\n  name = "t"\n',
    "block_brace_on_next_line": 'resource "google_pubsub_topic" "t"\n{\n  name = "t"\n}\n',
    "invalid_expression": 'resource "google_pubsub_topic" "t" {\n  name = \n}\n',
    "argument_or_block_required": 'resource "google_pubsub_topic" "t" {\n  name = "t"\n  ]\n}\n',
    "unterminated_string": 'resource "google_pubsub_topic" "t" {\n  name = "t\n}\n',
    "extra_closing_brace": 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n}\n',
}
