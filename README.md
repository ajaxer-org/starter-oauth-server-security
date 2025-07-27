# OAuth Security Starter

Starter for integrating with AjaxerOrg Authentication Server (JWT, filters, utils)A Spring Boot Starter to easily
integrate JWT-based authentication using `@EnableOAuthServerSecurity` annotation.

### Usage Example:

```java

@SpringBootApplication
@EnableOAuthServerSecurity
public class MyApplication
{
	public static void main(String[] args)
	{
		SpringApplication.run(MyApplication.class, args);
	}
}
```

### Maven

```xml
<dependency>
    <groupId>org.ajaxer.springframework</groupId>
    <artifactId>starter-oauth-server-security</artifactId>
    <version>1.0.0</version>
</dependency>
```
