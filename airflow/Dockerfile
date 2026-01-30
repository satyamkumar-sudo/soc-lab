FROM apache/airflow:2.9.3-python3.11

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

USER airflow
COPY requirements.txt /opt/soc/requirements.txt
RUN pip install --no-cache-dir -r /opt/soc/requirements.txt

# Put SOC python modules on PYTHONPATH for DAG imports.
ENV PYTHONPATH="/opt/soc:/opt/airflow:${PYTHONPATH}"

