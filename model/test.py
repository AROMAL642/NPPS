from nfstream import NFStreamer

streamer = NFStreamer(source="wlan0", statistical_analysis=True)
for flow in streamer:
    print(dir(flow))  # This shows all available attributes
    break

