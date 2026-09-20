"""
Download CICIDS2017 Improved dataset from Kaggle into the path expected
by train_pipeline.py:  ingestion/dataset/CICIDS2017_improved/
"""
import os
import sys
import zipfile
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # SIH_2026/
DEST = ROOT / "ingestion" / "dataset" / "CICIDS2017_improved"

REQUIRED_COLUMNS = {
    "Total Fwd Packet", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Min", "Fwd IAT Max", "Fwd PSH Flags", "Fwd URG Flags",
    "Fwd RST Flags", "Protocol", "Label"
}

KAGGLE_DATASET = "vencerlanz09/improved-cicids2017-and-csecicids2018"


def check_kaggle_token():
    token_path = Path.home() / ".kaggle" / "kaggle.json"
    if not token_path.exists():
        print("\n No Kaggle API token found at:", token_path)
        print("\nTo get your token:")
        print("  1. Go to https://www.kaggle.com/settings/account")
        print("  2. Scroll to API section, click Create New Token")
        print("  3. A kaggle.json file will download")
        print(f"  4. Move it to: {token_path}")
        print("  5. Re-run this script\n")
        sys.exit(1)
    print("Kaggle token found")


def download():
    import kaggle
    DEST.mkdir(parents=True, exist_ok=True)
    tmp = ROOT / ".tmp_cicids_download"
    tmp.mkdir(exist_ok=True)
    print(f"\nDownloading '{KAGGLE_DATASET}' ...")
    print("   This is ~500 MB, please wait...\n")
    kaggle.api.dataset_download_files(KAGGLE_DATASET, path=str(tmp), unzip=False, quiet=False)
    zips = list(tmp.glob("*.zip"))
    if not zips:
        raise FileNotFoundError("No zip found in .tmp_cicids_download/")
    zip_path = zips[0]
    print(f"\nExtracting {zip_path.name} ...")
    with zipfile.ZipFile(zip_path, "r") as z:
        members = z.namelist()
        cicids17_files = [m for m in members if m.endswith(".csv") and "2018" not in m.upper()]
        print(f"   Extracting {len(cicids17_files)} of {len(members)} files (CICIDS2017 only)")
        for member in cicids17_files:
            z.extract(member, tmp)
    count = 0
    for csv_file in tmp.rglob("*.csv"):
        if "2018" in csv_file.name.upper():
            continue
        shutil.move(str(csv_file), DEST / csv_file.name)
        count += 1
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\nExtracted {count} CSV files to {DEST}\n")


def validate():
    import pandas as pd
    csvs = list(DEST.glob("*.csv"))
    if not csvs:
        print(f"No CSV files in {DEST}")
        return False
    print(f"Validating {len(csvs)} CSV files...")
    all_ok = True
    for csv in sorted(csvs):
        try:
            df = pd.read_csv(csv, nrows=2)
            missing = REQUIRED_COLUMNS - set(df.columns)
            if missing:
                print(f"  WARNING {csv.name}: missing columns {missing}")
                all_ok = False
            else:
                size_mb = csv.stat().st_size / 1e6
                print(f"  OK {csv.name} ({size_mb:.1f} MB)")
        except Exception as e:
            print(f"  ERROR {csv.name}: {e}")
            all_ok = False
    return all_ok


if __name__ == "__main__":
    print("CICIDS2017 Dataset Downloader for SIH26145")
    check_kaggle_token()
    if DEST.exists() and any(DEST.glob("*.csv")):
        print(f"\nDataset already exists at {DEST}")
        validate()
        sys.exit(0)
    download()
    ok = validate()
    if ok:
        print(f"\nDataset ready! Now run:")
        print(f"   python train_pipeline.py --cicids ingestion/dataset/CICIDS2017_improved")
    sys.exit(0 if ok else 1)
