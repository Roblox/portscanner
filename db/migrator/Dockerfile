FROM public.ecr.aws/lambda/python:3.12

COPY db/migrator /tmp/portscanner-migrator
RUN pip install --no-cache-dir /tmp/portscanner-migrator \
    && rm -rf /tmp/portscanner-migrator

COPY db/migrations /opt/act/migrations
ENV MIGRATIONS_PATH=/opt/act/migrations

CMD ["act_migrator.handler.lambda_handler"]
