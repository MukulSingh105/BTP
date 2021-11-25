import streamlit as st
import pandas as pd
import numpy as np
import time


st.set_page_config(layout="wide")

st.title("Network Security Dashboard")

st.sidebar.title('Navigation')

st.sidebar.write("\n\n")

st.markdown("<h5> This is the security dashboard for monitoring connection security and enforcing the CIA triad. You can navigate the dashboard here", unsafe_allow_html=True)

if 'cat' not in st.session_state:
    st.session_state.cat = "Network"

st.sidebar.write("\n\n")

st.sidebar.subheader("Select Category to view Deatialed Statistics")
add_selectbox = st.sidebar.selectbox(
    " Select Category",
    ("Network", "Devices", "Blockchain", "Cloud Monitoring")
)

sub = st.sidebar.button("Submit")
if sub:
    st.session_state.cat = add_selectbox
    st.experimental_rerun()

st.sidebar.write("\n\n")

agree1 = st.sidebar.checkbox('Show Device Level Statistics', value=True)
agree2 = st.sidebar.checkbox("Show Cloud Threat Analysis", value=True)
agree3 = st.sidebar.checkbox("Sniff Live Packets", value=False)

st.sidebar.write("\n\n")

st.sidebar.subheader("Select Network on which the devices are online")
add_selectbox = st.sidebar.selectbox(
    " Select Network",
    ("Ethernet", "WiFi", "Bluetooth")
)

if st.session_state.cat == "Network":

    data = pd.read_csv("Devices.csv")

    df = data[["IP", "Port", "Nature"]]

    col1, col2, col3 = st.columns(3)

    col1.metric("Registered Devices", "8", "2")
    col1.table(df)

    col2.metric("Active Devices", "7", "-1")
    col2.table(df[data["Status"]==1])

    col3.metric("Blacklisted Devices", "1", "1")
    col3.table(df[data["Status"]==2])

    st.write("\n")

    col1, col2, col3 = st.columns(3)
    col1.line_chart(data["Time"])
    col2.line_chart(data[data["Status"]==1]["Time"])
    col3.line_chart(data[data["Status"]==2]["Time"])

    st.write("\n\n")

    st.subheader("Current Network Graph")

    st.write("\n\n")

    st.markdown("<h5> This is the current state of network graph and this represents current connections. Red nodes are blacklisted. Green Nodes are active Subscribers and Blue nodes are active Publishers", unsafe_allow_html=True)

    st.graphviz_chart('''
        digraph {
            Subscriber1 [color = green]
            Subscriber2 [color = green]
            Publisher1 [color = blue]
            Publisher2 [color = blue]
            Publisher3 [color = blue]
            Publisher4 [color = blue]
            Publisher5 [color = red]
            Publisher6 [color = blue]
            Subscriber1 -> Publisher1
            Subscriber2 -> Publisher2
            Subscriber1 -> Publisher2
            Subscriber1 -> Publisher6
            Subscriber2 -> Publisher3
            Subscriber2 -> Publisher4
            Publisher1 -> Subscriber1
            Publisher1 -> Subscriber2
            Publisher2 -> Subscriber1
            Publisher3 -> Subscriber2
            Publisher4 -> Subscriber2
            Publisher6 -> Subscriber1
        }
    ''', use_container_width=True)

if st.session_state.cat == "Devices":
    chain = pd.read_csv("Devices.csv")
    st.legacy_caching.clear_cache()
    for index, row in chain.iterrows():
        time.sleep(1)
        with st.expander("Device-"+str(index), expanded=False):
            st.write("TimeStamp : " + str(row["Time"]))
            st.write("Status : " + str(row["Status"]))
            st.write("IP Address : " + str(row["IP"]))
            st.write("Port Number : " + str(row["Port"]))
            st.write("Type : " + str(row["Nature"]))


if st.session_state.cat == "Blockchain":
    chain = pd.read_csv("Blockchain.csv")
    st.legacy_caching.clear_cache()
    for index, row in chain.iterrows():
        time.sleep(1)
        with st.expander("Block-"+str(index), expanded=False):
            st.write("TimeStamp : " + str(row["Time"]))
            st.write("Authenticators : " + str(row["Num_Auth"]))
            st.write("Miner ID : " + str(row["Added By"]))
            st.write("Merkle Root Hash : " + str(row["hash Merkle Root"]))
            st.write("Block Hash : " + str(row["Block Hash"]))
            st.write("Previous Block Hash : " + str(row["hash Prev Block"]))

if st.session_state.cat == "Cloud Monitoring":
    features = pd.read_csv("vinchuca.csv")
    st.subheader("Features Extracted")
    st.dataframe(features)
    st.subheader("Results")
    results = pd.read_csv("Cloud.csv")
    st.dataframe(results)
