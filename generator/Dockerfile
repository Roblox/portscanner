# syntax=docker/dockerfile:1.7
FROM public.ecr.aws/lambda/python:3.12

COPY contracts /opt/build/contracts
COPY inventory /opt/build/inventory
COPY generator /opt/build/generator
RUN python -m pip install --no-cache-dir \
    /opt/build/contracts \
    /opt/build/inventory \
    /opt/build/generator \
    && rm -rf /opt/build

CMD ["portscanner_generator.handler.lambda_handler"]
