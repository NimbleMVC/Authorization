<?php

namespace NimblePHP\Authorization\Exceptions;

use Exception;

/**
 * Exception thrown when validation fails
 * 
 * Used for user input validation errors like:
 * - Empty fields
 * - Invalid email format
 * - Password too short
 * - Username/email already exists
 * 
 * @package NimblePHP\Authorization\Exceptions
 */
class ValidationException extends Exception
{
    /**
     * Validation error field name
     * @var string|null
     */
    private ?string $field = null;

    /**
     * Set the field that failed validation
     * 
     * @param string $field Field name
     * @return self
     */
    public function setField(string $field): self
    {
        $this->field = $field;
        
        return $this;
    }

    /**
     * Get the field that failed validation
     * 
     * @return string|null
     */
    public function getField(): ?string
    {
        return $this->field;
    }
}
