<?php

/**
 * Entity model for access_token table
 *
 * PHP version 8
 *
 * Copyright (C) Villanova University 2023.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @category VuFind
 * @package  Database
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 */

namespace VuFind\Db\Entity;

use Doctrine\ORM\Mapping as ORM;
use DateTime;
use VuFind\Db\Entity\UserInterfaceEntity;
use VuFind\Db\Entity\LoginTokenInterfaceEntity;

/**
 * Entity model for login_token table
 *
 * @category VuFind
 * @package  Database
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 *
 * @ORM\Table(name="login_token")
 * @ORM\Entity
 */
class LoginToken implements LoginTokenEntityInterface
{
    /**
     * Unique ID.
     *
     * @var string
     *
     * @ORM\Column(name="id",
     *          type="integer",
     *          nullable=false
     * )
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="NONE")
     */
    protected $id;

    /**
     * User ID.
     *
     * @var User
     *
     * @ORM\ManyToOne(targetEntity="VuFind\Db\Entity\User")
     * @ORM\JoinColumns({
     * @ORM\JoinColumn(name="user_id",
     *              referencedColumnName="id")
     * })
     */
    protected $user;

    /**
     * Token.
     *
     * @var string
     *
     * @ORM\Column(name="token",
     *             type="string",
     *             length=255,
     *             nullable=false
     * )
     */
    protected $token;

    /**
     * Series.
     *
     * @var string
     *
     * @ORM\Column(name="series",
     *             type="string",
     *             length=255,
     *             nullable=false
     * )
     */
    protected $series;

    /**
     * Last login date.
     *
     * @var \DateTime
     *
     * @ORM\Column(name="last_login",
     *          type="datetime",
     *          nullable=false
     * )
     */
    protected $lastLogin = '2000-01-01 00:00:00';

    /**
     * Browser.
     *
     * @var ?string
     *
     * @ORM\Column(name="browser",
     *             type="string",
     *             length=255,
     *             nullable=true
     * )
     */
    protected $browser;

    /**
     * Platform.
     *
     * @var ?string
     *
     * @ORM\Column(name="platform",
     *             type="string",
     *             length=255,
     *             nullable=true
     */
    protected $platform;

    /**
     * Expires.
     *
     * @var int
     *
     * @ORM\Column(name="expires",
     *             type="integer",
     *             nullable=false
     * )
     */
    protected $expires;

    /**
     * Last session ID.
     *
     * @var ?string
     *
     * @ORM\Column(name="last_session_id",
     *             type="string",
     *             length=255,
     *             nullable=true
     */
    protected $lastSessionId;

    /**
     * Getter for ID.
     *
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * Setter for User.
     *
     * @param UserEntityInterface $user User to set
     *
     * @return LoginTokenEntityInterface
     */
    public function setUser(UserEntityInterface $user): LoginTokenEntityInterface
    {
        $this->user_id = $user->getId();
        return $this;
    }

    /**
     * User getter (only null if entity has not been populated yet).
     *
     * @return ?UserEntityInterface
     */
    public function getUser(): ?UserEntityInterface
    {
        return $this->user_id
            ? $this->getDbServiceManager()->get(UserServiceInterface::class)->getUserById($this->user_id)
            : null;
    }

    /**
     * Set token string.
     *
     * @param string $token Token
     *
     * @return LoginTokenEntityInterface
     */
    public function setToken(string $token): LoginTokenEntityInterface
    {
        $this->token = $token;
        return $this;
    }

    /**
     * Get token string.
     *
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Set series string.
     *
     * @param string $series Series
     *
     * @return LoginTokenEntityInterface
     */
    public function setSeries(string $series): LoginTokenEntityInterface
    {
        $this->series = $series;
        return $this;
    }

    /**
     * Get series string.
     *
     * @return string
     */
    public function getSeries(): string
    {
        return $this->series;
    }

    /**
     * Set last login date/time.
     *
     * @param DateTime $dateTime Last login date/time
     *
     * @return LoginTokenEntityInterface
     */
    public function setLastLogin(DateTime $dateTime): LoginTokenEntityInterface
    {
        $this->last_login = $dateTime->format('Y-m-d H:i:s');
        return $this;
    }

    /**
     * Get last login date/time.
     *
     * @return DateTime
     */
    public function getLastLogin(): DateTime
    {
        return DateTime::createFromFormat('Y-m-d H:i:s', $this->last_login);
    }

    /**
     * Set browser details (or null for none).
     *
     * @param ?string $browser Browser details (or null for none)
     *
     * @return LoginTokenEntityInterface
     */
    public function setBrowser(?string $browser): LoginTokenEntityInterface
    {
        $this->browser = $browser;
        return $this;
    }

    /**
     * Get browser details (or null for none).
     *
     * @return ?string
     */
    public function getBrowser(): ?string
    {
        return $this->browser;
    }

    /**
     * Set platform details (or null for none).
     *
     * @param ?string $platform Platform details (or null for none)
     *
     * @return LoginTokenEntityInterface
     */
    public function setPlatform(?string $platform): LoginTokenEntityInterface
    {
        $this->platform = $platform;
        return $this;
    }

    /**
     * Get platform details (or null for none).
     *
     * @return ?string
     */
    public function getPlatform(): ?string
    {
        return $this->platform;
    }

    /**
     * Set expiration timestamp.
     *
     * @param int $expires Expiration timestamp
     *
     * @return LoginTokenEntityInterface
     */
    public function setExpires(int $expires): LoginTokenEntityInterface
    {
        $this->expires = $expires;
        return $this;
    }

    /**
     * Get expiration timestamp.
     *
     * @return int
     */
    public function getExpires(): int
    {
        return $this->expires;
    }

    /**
     * Set last session ID (or null for none).
     *
     * @param ?string $sid Last session ID (or null for none)
     *
     * @return LoginTokenEntityInterface
     */
    public function setLastSessionId(?string $sid): LoginTokenEntityInterface
    {
        $this->last_session_id = $sid;
        return $this;
    }

    /**
     * Get last session ID (or null for none).
     *
     * @return ?string
     */
    public function getLastSessionId(): ?string
    {
        return $this->last_session_id;
    }
}