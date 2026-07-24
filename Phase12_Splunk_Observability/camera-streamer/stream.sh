#!/bin/sh
echo "Waiting for mediamtx to start..."
sleep 5
echo "Starting RTSP dummy stream generation..."

ffmpeg -re -f lavfi -i testsrc=size=1280x720:rate=15 \
       -vf "drawtext=fontfile=/usr/share/fonts/ttf-dejavu/DejaVuSans.ttf:text='SECURE AREA - FACILITY CAM 01':fontcolor=white:fontsize=48:box=1:boxcolor=black@0.5:boxborderw=5:x=(w-text_w)/2:y=50, \
            drawtext=fontfile=/usr/share/fonts/ttf-dejavu/DejaVuSans.ttf:text='%{localtime}':fontcolor=white:fontsize=36:box=1:boxcolor=black@0.5:boxborderw=5:x=w-text_w-20:y=h-text_h-20" \
       -c:v libx264 -preset ultrafast -maxrate 1000k -bufsize 2000k -pix_fmt yuv420p -g 30 \
       -f rtsp -rtsp_transport tcp rtsp://mediamtx:8554/cam1
