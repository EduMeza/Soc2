from app.services.csv_parser import load_csv

with open(r'C:\Users\emeza.LEGACY\Documents\Proyectos\Soc2\data\sample_events_1.csv', 'rb') as f:
    contents = f.read()

print(f"File size: {len(contents)} bytes")

try:
    df, detected = load_csv(contents, max_mb=50, max_rows=200000)
    print(f"Rows: {len(df)}")
    print(f"Columns: {df.columns.tolist()}")
    print(f"Detected: {detected}")
    if len(df) > 0:
        print(df.head())
    else:
        print("DataFrame is empty!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()