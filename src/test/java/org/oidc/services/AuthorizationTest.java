package org.oidc.services;

import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.oidc.service.base.ServiceContext;

public class AuthorizationTest {

    private static final ServiceContext SERVICE_CONTEXT =
            new ServiceContext();

    @Test
    public void testSetState() {
        Map<String,String> requestArgs = new HashMap<>();
        requestArgs.put("state", "state");
        Authorization authorization = new Authorization(SERVICE_CONTEXT);
        authorization.setState(requestArgs);
    }
}
