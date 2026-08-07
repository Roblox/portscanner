FROM public.ecr.aws/lambda/python:3.12

COPY contracts /tmp/portscanner-contracts
COPY parser /tmp/portscanner-parser
RUN pip install --no-cache-dir /tmp/portscanner-contracts /tmp/portscanner-parser \
    && rm -rf /tmp/portscanner-contracts /tmp/portscanner-parser

COPY processor /tmp/portscanner-processor
RUN pip install --no-cache-dir /tmp/portscanner-processor \
    && rm -rf /tmp/portscanner-processor

CMD ["act_processor.handler.lambda_handler"]
