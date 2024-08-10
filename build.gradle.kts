plugins {
	java
	id("org.springframework.boot") version "3.1.1"
	id("io.spring.dependency-management") version "1.1.0"
	id("io.freefair.lombok") version "8.1.0"
}

group = "simplesso"
version = "0.0.1-SNAPSHOT"

java {
	sourceCompatibility = JavaVersion.VERSION_17
}

repositories {
	mavenCentral()
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
	implementation("org.springframework.boot:spring-boot-starter-web")
	implementation("com.google.crypto.tink:tink:1.9.0")
	implementation("org.slf4j:slf4j-api:2.0.7")
	implementation("org.slf4j:jcl-over-slf4j:2.0.7")
	runtimeOnly("org.postgresql:postgresql")

	testImplementation("org.springframework.boot:spring-boot-starter-test")
	runtimeOnly("com.h2database:h2:2.2.220")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
