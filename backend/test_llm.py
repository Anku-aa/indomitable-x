"""Smoke-test the zero-configuration natural-language parser."""

from llm import interpret


QUERIES = [
    "Show employees in Sales and their job roles",
    "List departments and education levels",
    "What is the average monthly income by department?",
    "Count employees in the Finance department",
    "Update the performance rating for employee 1001",
    "Delete employee with id 1001",
]


if __name__ == "__main__":
    for query in QUERIES:
        print(f"Request: {query}")
        print(f"Parsed: {interpret(query)}")
