package com.sentinelpr.fixture.coupled;

/**
 * Data Transfer Object encapsulating User attributes without internal schema leakage.
 */
public class UserDto {

    private String id;
    private String username;
    private String email;

    public UserDto() {
    }

    public UserDto(String id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }

    public static UserDto fromEntity(UserEntity entity) {
        if (entity == null) {
            return null;
        }
        return new UserDto(entity.getId(), entity.getUsername(), entity.getEmail());
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
