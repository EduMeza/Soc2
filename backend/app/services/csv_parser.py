import csv
import io
from app.services.normalization import detect_columns, normalize_row

def parse_csv(content, max_mb=50, max_rows=200000):
    if len(content) > max_mb * 1024 * 1024:
        raise ValueError('CSV demasiado grande')
    try:
        text = content.decode('utf-8-sig')
    except UnicodeDecodeError:
        text = content.decode('latin-1')
    try:
        delimiter = csv.Sniffer().sniff(text[:65536], delimiters=',;\t|').delimiter
    except csv.Error:
        header = text.splitlines()[0] if text else ''
        delimiter = max(',;\t|', key=header.count)
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames or len(reader.fieldnames) > 80:
        raise ValueError('Encabezado CSV inválido')
    detected = detect_columns(reader.fieldnames)
    events, warnings, rejected, total = [], [], 0, 0
    for number, row in enumerate(reader, 2):
        total += 1
        if total > max_rows:
            raise ValueError('Límite de filas excedido')
        try:
            if None in row or any(v is None for v in row.values()):
                raise ValueError('Cantidad de columnas inconsistente')
            event, notes = normalize_row(row, detected)
            events.append(event)
            warnings.extend({'row': number, 'message': n} for n in notes)
        except ValueError as exc:
            rejected += 1
            warnings.append({'row': number, 'message': str(exc)})
    return events, detected, warnings, rejected, total
