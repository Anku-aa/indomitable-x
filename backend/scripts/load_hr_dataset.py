"""Load HR_Dataset.csv into a separate SQLite database for realistic testing."""

import argparse
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine


DEFAULT_CSV = Path(__file__).resolve().parents[1] / "data" / "HR_Dataset.csv"
DEFAULT_DB_URL = "sqlite:///./hr_demo.db"


def load_dataset(csv_path: str | Path = DEFAULT_CSV, db_url: str = DEFAULT_DB_URL) -> int:
    dataframe = pd.read_csv(csv_path)
    if dataframe.empty:
        raise ValueError("The HR dataset is empty")
    engine = create_engine(db_url, connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {})
    dataframe.to_sql("hr_records", engine, if_exists="replace", index=False, chunksize=500, method="multi")
    return len(dataframe)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default=str(DEFAULT_CSV))
    parser.add_argument("--db-url", default=DEFAULT_DB_URL)
    args = parser.parse_args()
    count = load_dataset(args.csv, args.db_url)
    print(f"Loaded {count} rows from {args.csv} into hr_records using {args.db_url}")
