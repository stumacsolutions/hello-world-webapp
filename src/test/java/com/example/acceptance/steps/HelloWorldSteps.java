package com.example.acceptance.steps;

import com.example.Application;
import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.HttpStatus.OK;

@ContextConfiguration(classes = Application.class)
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class HelloWorldSteps {
    @Autowired
    private TestRestTemplate restTemplate;

    private ResponseEntity<String> response;

    @Given("^the application is running$")
    public void givenTheApplicationIsRunning() throws Throwable {
        // Write code here that turns the phrase above into concrete actions
    }

    @When("^i say hello to the application$")
    public void whenISayHelloToTheApplication() throws Throwable {
        response = restTemplate.getForEntity("/", String.class);
    }

    @Then("^the application should say hello to me$")
    public void thenTheApplicationShouldSayHelloToMe() throws Throwable {
        assertNotNull(response);
        assertEquals(OK, response.getStatusCode());
        assertEquals("Hello, World.", response.getBody());
    }
}
