"""Read-only CSV diagnostic: no runtime writes."""
from pathlib import Path
from app.services.csv_parser import parse_csv

if __name__ == '__main__':
    content = (Path(__file__).resolve().parents[1]/'data/sample_events_1.csv').read_bytes()
    events,columns,warnings,rejected,total = parse_csv(content)
    print({'total_rows':total,'valid':len(events),'rejected':rejected,'columns':columns,'warnings':warnings})
