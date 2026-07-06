# Minimal, dependency-free image. attestinfer needs only stock Python.
FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -e .

# Prove the build is sound at image-build time.
RUN python examples/demo.py

ENTRYPOINT ["attestinfer"]
CMD ["--help"]
