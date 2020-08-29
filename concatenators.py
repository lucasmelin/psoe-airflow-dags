from airflow import DAG
from airflow.operators.python_operator import PythonOperator
import csv
from datetime import datetime, timedelta
from airflow.hooks.base_hook import BaseHook
import logging


def create_dag(dag_id, schedule, dag_number, default_args):
    def concatenate_values(*args):
        lst = []
        for i in range(100000):
            lst.append("x")

    dag = DAG(dag_id, schedule_interval=schedule, default_args=default_args)

    with dag:
        t1 = PythonOperator(
            task_id="concatenator",
            python_callable=concatenate_values,
            dag_number=dag_number,
        )

    return dag


# build a dag for each number in range(4)
for n in range(1, 11):
    dag_id = "concatenator_{}".format(str(n))

    default_args = {"owner": "airflow", "start_date": datetime(2020, 1, 1)}
    schedule = "@daily"
    dag_number = n
    globals()[dag_id] = create_dag(dag_id, schedule, dag_number, default_args)
