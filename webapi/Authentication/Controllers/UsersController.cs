using Authentication.Data;
using Authentication.Dtos;
using Authentication.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]/[action]")]
    public class UsersController : Controller
    {
        private readonly DataContext _context;

        public UsersController(DataContext context)
        {
            _context = context;
        }
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new System.Security.Cryptography.HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
        [HttpDelete("{id}")]
        [HttpDelete("{id}/{systemCodeID}")]
        public async Task<IActionResult> Delete(int id, int systemCodeID)
        {
            if (id > 0 && systemCodeID > 0)
            {
                var entity = await _context.Users.FirstOrDefaultAsync(x => x.ID == id);
                if (entity == null)
                {
                    return NotFound();
                }
                try
                {
                    var item = await _context.UserSystems.FirstOrDefaultAsync(x => x.SystemID == systemCodeID && x.UserID == id);
                    if (item == null)
                    {
                        return Ok(true);
                    }
                    entity.IsShow = false;
                    _context.Users.Update(entity);
                    _context.UserSystems.Remove(item);
                    await _context.SaveChangesAsync();
                    return Ok(true);
                }
                catch
                {
                    return Ok(false);

                }
            }
            else
            {
                var entity = await _context.Users.FindAsync(id);
                if (entity == null)
                {
                    return NotFound();
                }

                try
                {
                    entity.IsShow = false;
                    _context.Users.Update(entity);
                    await _context.SaveChangesAsync();
                    return Ok();
                }
                catch (Exception ex)
                {
                    return BadRequest(ex.Message);
                }
            }
        }
        [HttpDelete]
        public async Task<IActionResult> Delete(int id)
        {
            var entity = await _context.Users.FindAsync(id);
            if (entity == null)
            {
                return NotFound();
            }

            try
            {
                entity.IsShow = false;
                _context.Users.Update(entity);
                await _context.SaveChangesAsync();
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost]
        public async Task<IActionResult> Create(UpdateUserDto entity)
        {
            var item = await _context.Users.FirstOrDefaultAsync(x => x.EmployeeID.ToLower().Equals(entity.EmployeeID.ToLower()));
            if (item == null)
            {
                byte[] passwordHash, passwordSalt;
                CreatePasswordHash(entity.Password, out passwordHash, out passwordSalt);
                var user = new User
                {
                    Username = entity.Username,
                    Email = entity.Email,
                    EmployeeID = entity.EmployeeID,
                    IsShow = true,
                    LevelOC = entity.LevelOC,
                    OCID = entity.OCID,
                    RoleID = entity.RoleID
                };
                user.PasswordHash = passwordHash;
                user.PasswordSalt = passwordSalt;
                user.ModifyTime = DateTime.Now;
                user.IsShow = true;
                await _context.Users.AddAsync(user);
                try
                {
                    await _context.SaveChangesAsync();
                    _context.UserSystems.Add(new UserSystem
                    {
                        UserID = user.ID,
                        SystemID = entity.SystemCode,
                        Status = true,
                        DateTime = DateTime.UtcNow
                    });
                    await _context.SaveChangesAsync();
                    return Ok(user.ID);
                }
                catch (Exception ex)
                {
                    return BadRequest(ex.Message);
                }
            }
            else
            {
                if (item.IsShow == false)
                {
                    item.IsShow = true;
                    _context.Update(item);
                    await _context.SaveChangesAsync();
                }
                var userSystem = await _context.UserSystems.FirstOrDefaultAsync(x => x.UserID == item.ID && x.SystemID == entity.SystemCode);
                if (userSystem == null)
                {
                    _context.UserSystems.Add(new UserSystem
                    {
                        UserID = item.ID,
                        SystemID = entity.SystemCode,
                        Status = true,
                        DateTime = DateTime.UtcNow
                    });
                    await _context.SaveChangesAsync();
                    return Ok(item.ID);
                }
                else
                {
                    try
                    {
                        _context.UserSystems.Remove(userSystem);
                        await _context.SaveChangesAsync();
                        return Ok(item.ID);
                    }
                    catch (Exception ex)
                    {
                        return BadRequest(ex.Message);
                    }
                }
            }

        }
        [HttpPost]
        public async Task<IActionResult> Update(UpdateUserDto entity)
        {
            var item = await _context.Users.FindAsync(entity.ID);
            item.EmployeeID = entity.EmployeeID;
            item.Username = entity.Username;
            item.Email = entity.Email;
            item.ModifyTime = DateTime.Now;
            item.RoleID = 2;
            if (!string.IsNullOrEmpty(entity.Password))
            {
                byte[] passwordHash, passwordSalt;
                CreatePasswordHash(entity.Password, out passwordHash, out passwordSalt);
                item.PasswordHash = passwordHash;
                item.PasswordSalt = passwordSalt;
            }

            item.ModifyTime = DateTime.Now;

            try
            {
                _context.Users.Update(item);
                await _context.SaveChangesAsync();
                return NoContent();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [AllowAnonymous]
        [HttpGet("{systemID}")]
        public async Task<ActionResult> GetUserBySystemID(int systemID)
        {
            var model = from a in _context.Users.Where(x => x.IsShow)
                        join b in _context.UserSystems on a.ID equals b.UserID
                        where b.SystemID == systemID
                        select new User
                        {
                            ID = a.ID,
                            Username = a.Username,
                            Email = a.Email,
                            EmployeeID = a.EmployeeID,
                        };
            var data = await model.ToListAsync();
            return Ok(data);
        }
    }
}
