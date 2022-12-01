sudo tshark -i enp0s3 -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e ip.len -e ip.flags.df  -e ip.proto -e tcp.stream -e frame.time_relative -e frame.time_delta > live.csv
