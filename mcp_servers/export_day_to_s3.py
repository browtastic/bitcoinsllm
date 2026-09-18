#!/usr/bin/env python3
"""
export_day_to_s3.py — bulk-export one day of the acv-research log group to S3,
then pull it down so the correlator can run on a full same-day window.

WHY: attribution.jsonl on the box is logrotate-truncated daily, so
correlate_sessions.py only ever sees a partial window and chat-driven loopback
calls end up ~2h from their chat turns (a data-coverage artifact, not a bug). It
also means a recurring actor like 35.186.14.156 may have ZERO rows in today's
local log while being very present in CloudWatch history. Exporting the day's full
log group to S3 and correlating against THAT fixes both.

RUN FROM ADMIN / LAPTOP CREDS — the box instance role deliberately cannot
s3:PutObject or create export tasks. create_export_task also requires the target
bucket to allow the CloudWatch Logs service to write (one-time bucket policy, see
--print-bucket-policy).

Usage:
  # one-time: show the bucket policy CloudWatch Logs needs, then apply it
  python export_day_to_s3.py --print-bucket-policy --bucket acv-exports

  # export today (UTC) and pull the attribution stream down for the correlator
  python export_day_to_s3.py --bucket acv-exports --date 2026-08-26 --pull

  # then correlate on the full-day export:
  python correlate_sessions.py \
      --attribution ./export-2026-08-26/attribution/*.gz --window 120

Notes:
  - Export granularity is the whole log group; streams land under
    s3://<bucket>/<prefix>/<taskId>/<logStreamName>/*.gz (gzip).
  - --pull downloads the task output and gunzips the attribution stream into
    ./export-<date>/attribution/ for direct use by the correlator.
"""
import argparse, gzip, io, json, os, sys, time, datetime as dt

try:
    import boto3
except Exception:
    print("boto3 required (run from laptop/admin env)"); sys.exit(1)

GROUP_DEFAULT = "acv-research"

BUCKET_POLICY_TMPL = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "CWLGetBucketAcl", "Effect": "Allow",
         "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
         "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::%(bucket)s"},
        {"Sid": "CWLPutObject", "Effect": "Allow",
         "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
         "Action": "s3:PutObject", "Resource": "arn:aws:s3:::%(bucket)s/*",
         "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
    ],
}

def day_bounds_ms(date_str):
    d = dt.datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
    start = int(d.timestamp() * 1000)
    end   = int((d + dt.timedelta(days=1)).timestamp() * 1000)
    return start, end

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--group", default=GROUP_DEFAULT)
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"))
    ap.add_argument("--prefix", default="acv-exports")
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    ap.add_argument("--pull", action="store_true", help="download + gunzip attribution stream after export")
    ap.add_argument("--print-bucket-policy", action="store_true")
    args = ap.parse_args()

    if args.print_bucket_policy:
        pol = json.dumps(BUCKET_POLICY_TMPL).replace("%(bucket)s", args.bucket)
        print("Apply once so CloudWatch Logs may write to the bucket:\n")
        print(f"aws s3api put-bucket-policy --bucket {args.bucket} --policy '{pol}'")
        return

    start, end = day_bounds_ms(args.date)
    logs = boto3.client("logs", region_name=args.region)
    prefix = f"{args.prefix}/{args.date}"

    print(f"exporting group={args.group} date={args.date} -> s3://{args.bucket}/{prefix}")
    task = logs.create_export_task(
        logGroupName=args.group, fromTime=start, to=end,
        destination=args.bucket, destinationPrefix=prefix,
    )
    tid = task["taskId"]
    print(f"taskId={tid} — polling…")
    while True:
        desc = logs.describe_export_tasks(taskId=tid)["exportTasks"][0]
        st = desc["status"]["code"]
        if st in ("COMPLETED", "FAILED", "CANCELLED"):
            print(f"status={st}")
            if st != "COMPLETED":
                sys.exit(f"export {st}: {desc['status'].get('message','')}")
            break
        time.sleep(5)

    s3loc = f"s3://{args.bucket}/{prefix}/{tid}/"
    print(f"export complete: {s3loc}")

    if not args.pull:
        print("(re-run with --pull to download the attribution stream for the correlator)")
        return

    s3 = boto3.client("s3", region_name=args.region)
    outdir = os.path.join(f"export-{args.date}", "attribution")
    os.makedirs(outdir, exist_ok=True)
    key_prefix = f"{prefix}/{tid}/"
    n = 0
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=args.bucket, Prefix=key_prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if "attribution" not in key.lower():
                continue
            body = s3.get_object(Bucket=args.bucket, Key=key)["Body"].read()
            try:
                text = gzip.decompress(body).decode("utf-8", "replace")
            except OSError:
                text = body.decode("utf-8", "replace")
            fn = os.path.join(outdir, os.path.basename(key).replace(".gz", "") + ".jsonl")
            io.open(fn, "w", encoding="utf-8").write(text)
            n += 1
    print(f"pulled {n} attribution object(s) -> {outdir}/")
    print(f"now run:  python correlate_sessions.py --attribution {outdir}/*.jsonl --window 120")
    print(f"and:      grep 35.186.14.156 {outdir}/*.jsonl | wc -l   # 35.186 activity in the full day")

if __name__ == "__main__":
    main()
