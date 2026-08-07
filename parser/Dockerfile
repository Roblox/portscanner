FROM public.ecr.aws/lambda/python:3.12

COPY contracts /tmp/portscanner-contracts
COPY parser /tmp/portscanner-parser
RUN pip install --no-cache-dir /tmp/portscanner-contracts /tmp/portscanner-parser \
    && rm -rf /tmp/portscanner-contracts /tmp/portscanner-parser

CMD ["act_parser.handler.lambda_handler"]
