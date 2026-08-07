# syntax=docker/dockerfile:1.7
FROM public.ecr.aws/lambda/python:3.12

COPY contracts /opt/build/contracts
COPY inventory /opt/build/inventory
RUN python -m pip install --no-cache-dir /opt/build/contracts /opt/build/inventory \
    && rm -rf /opt/build

CMD ["portscanner_inventory.handlers.snapshot.lambda_handler"]
