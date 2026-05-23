FROM python:3.11-slim

# Build context will be the repository root so we can include sibling packages
WORKDIR /app
ENV PYTHONPATH=/app

# Copy scanner requirements and install
COPY scanner/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scanner package and the reporting package so imports resolve
COPY scanner /app/scanner
COPY reporting /app/reporting

EXPOSE 8080

# Run the WSGI app via module path `scanner.api:app`
CMD ["gunicorn", "--chdir", "/app", "-w", "2", "-b", "0.0.0.0:8080", "scanner.api:app"]