# PSD2 Sandbox Example
This is a simple example of how to use the PSD2 API provided by Íslandsbanki.

The example is written in .Net Core and uses the HttpClient to make requests to the API.

## Getting Started

### Create a developer account
To get started you need to create an account with Íslandsbanki.
Follow the steps and instructions found  [here](https://developer.islandsbanki.is/apiportal/#/home/landing?get-started.htm).


### Generating an access token
For the example to run, you need to authorize the client. That can be done with Postman, but detailed instructions can
be found [here](https://developer.islandsbanki.is/apiportal/#/home/landing?documentation.htm). The result from these
steps is an access token, that you need to add to the variable called `accessToken` in the `Program.cs` file.

## The flow of the program

The program initiates a payment between two accounts, belonging to the same user (user.0). Information about the test data
can be found [here](https://developer.islandsbanki.is/apiportal/#/home/landing?documentation.htm) under the tab `Test Data`.

1. Initiate Payment
2. Get payment information
3. Get payment status
4. Authorise payment
5. Get payment status
