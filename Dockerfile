FROM python:3.12 AS dev
WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-dev.txt .  

RUN pip install --no-cache-dir -r requirements-dev.txt  

CMD ["bash"]

FROM public.ecr.aws/lambda/python:3.12 AS lambda
WORKDIR /var/task

COPY requirements.txt . 
RUN pip install --no-cache-dir -r requirements.txt  

COPY --from=dev /usr/local/bin /usr/local/bin
COPY app.py .

CMD ["app.lambda_handler"]
