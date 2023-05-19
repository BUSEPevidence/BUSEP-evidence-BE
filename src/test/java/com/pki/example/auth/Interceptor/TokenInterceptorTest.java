package com.pki.example.auth.Interceptor;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@SpringBootTest
@AutoConfigureMockMvc
public class TokenInterceptorTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testInterceptor() throws Exception {
        // Send a mock request to the endpoint
        ResultActions resultActions = mockMvc.perform(MockMvcRequestBuilders.get("/HEY"));

        // Assert the expected behavior
        resultActions.andExpect(MockMvcResultMatchers.status().isOk());
        resultActions.andExpect(MockMvcResultMatchers.header().string("xd", "RADI JEBENO XD!"));
    }
}
