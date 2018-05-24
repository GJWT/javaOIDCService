package org.oidc.service.data;

import java.util.HashMap;
import java.util.Map;

public class StateMap {

    private static StateMap stateMap = null;

    public static StateMap getInstance() {
        if (stateMap == null)
            stateMap = new StateMap();

        return stateMap;
    }

    private StateMap() {

    }

    private Map<String,State> map =
            new HashMap<>();

    public Map<String, State> getStateMap() {
        return map;
    }

    public void setStateMap(Map<String, State> stateMap) {
        this.map = stateMap;
    }
}
