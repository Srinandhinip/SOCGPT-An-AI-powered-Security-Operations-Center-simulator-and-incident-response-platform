package com.socgpt.backend.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Put on a controller method (or class) to say which roles may call it.
 * Admins may always call it. Without this annotation, reading (GET) is open to any
 * signed-in user and every change (POST, PUT, DELETE) is admin-only: secure by default.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresRole {
    String[] value();
}
