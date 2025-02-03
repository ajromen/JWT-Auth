using JwtAuthStart.DTOs;
using JwtAuthStart.Models;

namespace JwtAuthStart.Interfaces.Services
{
    public interface IAuthService
    {
        Task<User?> ReisterAsync(UserDTO request);
        Task<string?> LoginAsync(UserDTO request);
    }
}
