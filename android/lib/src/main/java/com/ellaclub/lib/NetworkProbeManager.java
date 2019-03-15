package com.ellaclub.lib;

public class NetworkProbeManager {
    private static class NetworkProbeManagerINSTANCE {
        private static NetworkProbeManager instance = new NetworkProbeManager();
    }

    public static NetworkProbeManager getInstance() {
        return NetworkProbeManagerINSTANCE.instance;
    }

    public void init() {

    }

    public void destroy() {

    }

    public void start() {

    }

    public void stop() {

    }
}
