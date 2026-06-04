import pandas as pd
import streamlit as st


st.set_page_config(page_title="DangerScope Dashboard", layout="wide")

st.title("DangerScope Security Dashboard")

risk_file = "reports/risk_summary.csv"
alerts_file = "reports/alerts.json"

risk_df = pd.read_csv(risk_file)
alerts_df = pd.read_json(alerts_file)

st.subheader("Risk Summary")
st.dataframe(risk_df)

st.subheader("Alerts")
st.dataframe(alerts_df)

st.subheader("Alert Counts by Type")
alert_counts = alerts_df["type"].value_counts()
st.bar_chart(alert_counts)

st.subheader("Risk Scores by IP")
st.bar_chart(risk_df.set_index("ip")["score"])