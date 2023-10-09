for i in {11..20}
do
  curl "http://192.168.3.$i:8000/list"
done
