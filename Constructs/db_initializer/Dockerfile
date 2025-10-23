FROM public.ecr.aws/lambda/python:3.12-arm64

COPY requirements.txt ${LAMBDA_TASK_ROOT}
COPY handler.py ${LAMBDA_TASK_ROOT}

RUN dnf install -y gcc postgresql-devel

RUN pip3 install -r requirements.txt --target "${LAMBDA_TASK_ROOT}"

CMD ["handler.handler"]