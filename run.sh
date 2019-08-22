# Docker Automation Script

# Reference:
# * https://gist.github.com/rizkyario/96ef3ff65d0bba75b428598d711a3c03
# * https://medium.com/@SaravSun/running-gui-applications-inside-docker-containers-83d65c0db110
# * 

if [[ "$OSTYPE" == "darwin"* ]]; then
    # Mac OS -- xQuartz method

    # Install XQuartz and Docker
    brew cask install xquartz
    brew cask install docker

    # Open XQuartz - Manual step to allow XQuartz connects...
    # In the XQuartz preferences, go to the “Security” tab
    # Make sure you’ve got “Allow connections from network clients” ticked
    open -a XQuartz 

    # Setup ENV
    export IP=$(ifconfig -a | grep "inet " | sed 's/.*inet \([0-9\.]*\).*/\1/g' | grep -v "127.0.0.1" -m1)
    export DISPLAY=$IP:0

    # Add ENV to XQuartz
    /usr/X11/bin/xhost +

    # Create directory to share pcap and get report
    #mkdir ~/shared_volume

    # Run Docker Image - Production (Master)
    #docker run --rm -d --name pcapxray -e DISPLAY=$IP:0 -v /tmp/.X11-unix:/tmp/.X11-unix srinivas11789/pcapxray
    # Run Docker Image - Staging (Develop)
    docker run --rm -d --name pcapxray -v ${PWD}/artifacts:/tmp/artifacts -e DISPLAY=$IP:0 -v /tmp/.X11-unix:/tmp/.X11-unix srinivas11789/pcapxray-2_9
    echo "XQuartz should be started and incoming connections should be allowed for this to work."
    echo "Set the Report to /tmp/artifacts in UI to get reports in the shared directory /artifacts"

#elif [[ "$OSTYPE" == "linux-gnu" ]]; then
else
    # Linux OS -- SSH Method or xAuthority method

    # Install docker
    apt install -y docker.io
    service docker start

    # Run docker - Production (Master)
    #docker run --rm --net=host --env="DISPLAY" --volume="$HOME/.Xauthority:/root/.Xauthority:rw" srinivas11789/pcapxray
    # Run docker - Staging (Develop)
    docker run --rm -d --name pcapxray -v ${PWD}/artifacts:/tmp/artifacts --net=host --env="DISPLAY" --volume="$HOME/.Xauthority:/root/.Xauthority:rw" srinivas11789/pcapxray-2_9
    echo "Set the Report to /tmp/artifacts in UI to get reports in the shared directory /artifacts"
fi

#else
#    # Windows OS -- xming method
#    echo "Windows OS"
#    # choco install vcxsrv --> configure
#    # set-variable -name DISPLAY -value YOUR-IP:0.0
#    # docker run -ti --rm -e DISPLAY=$DISPLAY firefox
#fi

