using JwtAuthStart.DTOs;
using JwtAuthStart.Models;

namespace JwtAuthStart.Interfaces.Services
{
    public interface IAuthService
    {
        Task<User?> ReisterAsync(UserDto request);
        Task<TokenResponseDto?> LoginAsync(UserDto request);
        Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
    }
}
