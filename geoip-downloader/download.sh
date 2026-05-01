#!/bin/sh
set -e

apk add --no-cache wget ca-certificates > /dev/null 2>&1

if [ -f /geoip/city.mmdb ]; then
  echo "GeoIP database already present."
  exit 0
fi

# DB-IP publishes the new month's file on the 1st; on that day the file may not
# be ready yet, so try the current month first and fall back to the previous one.
CUR_YEAR=$(date +%Y)
CUR_MON=$(date +%m)

PREV_MON=$((10#$CUR_MON - 1))
PREV_YEAR=$CUR_YEAR
if [ "$PREV_MON" -eq 0 ]; then
  PREV_MON=12
  PREV_YEAR=$((CUR_YEAR - 1))
fi
PREV_MON=$(printf "%02d" $PREV_MON)

for YM in "${CUR_YEAR}-${CUR_MON}" "${PREV_YEAR}-${PREV_MON}"; do
  URL="https://download.db-ip.com/free/dbip-city-lite-${YM}.mmdb.gz"
  echo "Trying ${URL} ..."
  if wget -q --timeout=60 -O /geoip/city.mmdb.gz "${URL}"; then
    gunzip /geoip/city.mmdb.gz \
      && echo "GeoIP database ready (${YM})." \
      && exit 0
    rm -f /geoip/city.mmdb.gz /geoip/city.mmdb
  fi
  rm -f /geoip/city.mmdb.gz
done

echo "WARNING: GeoIP download failed — GeoIP enrichment will be skipped."
exit 0
